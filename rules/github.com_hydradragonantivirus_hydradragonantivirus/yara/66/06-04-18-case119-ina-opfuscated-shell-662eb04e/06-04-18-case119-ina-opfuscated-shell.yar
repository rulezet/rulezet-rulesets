rule _06_04_18_case119_ina_opfuscated_shell {
  meta:
    description = "case119 - file ina.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-04"
    hash1       = "c7bec8f3844658a2ed8f24a924a0b4e7e3ab21633b0a5fe15618face81b66222"

  strings:
    $s1  = "}eval(fUUPd(\"jbvnzvTQep53AAZ8Dhs7BiKFjlmGFYISsAx772QUCKzD3nuQYw8/SY71x95+AWJAcnGVZz3lvvjO/OUvf/6KI+n+Lk3WAkf/OS+yMS/+7q+cNXXZIB" ascii
    $s2  = "mem6jtsrLme3rCe7MIRbKnbCG9d1D4zQJNbm55mOfP0cbhuFa1GgPf69XtJJA2mCN5zjyZ2WvMiGcPKyqBN1sr4RRMQs8dKNWGeGRfirUjuPTadvsv2EvKMMOo73O/32" ascii
    $s3  = "4IRdK1notSriswdU3U2QpbhUYmOsV03G2U5RMBg1QvGMyDbPjLFDMyGozySdOy/3b0GAz3+KTIz8os8utkP+pOIlIrqmg/2XDLLKoivK/YfIKzllcnZ3lByeanYISO25" ascii
    $s4  = "6se8QJAlNt7zEAQjrctGaxrzKruCiQUIMncx+GXvPZaD7Dbf+4nq3wxue23v2u0PQd62FunMSpymzKaFsms+6Qaa/H7jqU1WVthDfOOrbLF6rI4PHmr2tVlMQjT/mGTq" ascii
    $s5  = "Ijj7mna+vhgrqDQgRuxz6JsS4BKpWoAE3Hn6lkMUmz9rZE7XRUYvpzZxX5nikY+iuzPvt4aypPM0WcGWq07KE9d7LmN79Urxqntateu7HpcQBMjrOhRsc47qQ8xIFAke" ascii
    $s6  = "75cBcduQRynPQ//q//dCHUfzs+zF//81//y1///h/+43/4S3HV2z/85f/9y//5f/x/\"));?>" fullword ascii
    $s7  = "+XW6rn2JNH6tgzIIjFZ2Zl/t7jS0AHgeOqhqxKvZUetqf84GGPmrxlPQtEklK606+eZg0Qyq2hIPSGidi0N7FObAfRQaTMPQBIHUX7bJdYv1KmoMA+GweWfj+AbcXP5f" ascii
    $s8  = "gGwaIVx+3CMT/c8rHEN257IhBYWQnSE0QE+lyPopjzXggweKqCz6fTh07jCSPzNGcXvjuhCZiefeHQnJM6b3cQIupERgs9cpIDraLMpGjpFVyVW6B+rE/NRXRBfKeYIn" ascii
    $s9  = "7/6CcmDVZUup3tL/EIpDIOfmt5xnh6VHqt3J6SAZTZawduotbg1WeuebwSVoaR3Rkn1EtmieufZ15pfg2lwnHx8rssD3hQNizMFKVMaYRg2hbpFz8nSKFzXG94vAmGHo" ascii
    $s10 = "rQqLxBHcbWp5gt3BalunJ+wVS8CmD8ndUvA1Ngx305VDELV7/L8fA1eD1y5JAIZn0W05NeqbbLabZIMPBxzt+sJfZE7qsfIOCsKDLcXxvaj84I89+JQnwl3n3TdkNN9a" ascii
    $s11 = "WyQnCcT7vqEiF7UqqlMQU/Tsb8g/NAc1glTzwiH3r2z8FrosdktMD7p97hsq+kPDmRnjImnmdlvdZ+xl83qLvkmZ92iC0oQrQ81sY0UH0ny/Y8T17ujeQWCmDuDY3E43" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 70KB and
      (8 of them)
    ) or (all of them)
}