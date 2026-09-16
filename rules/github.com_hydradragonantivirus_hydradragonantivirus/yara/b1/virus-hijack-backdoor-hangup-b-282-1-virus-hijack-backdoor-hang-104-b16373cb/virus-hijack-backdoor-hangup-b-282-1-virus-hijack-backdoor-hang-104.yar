import "pe"
rule _Virus_Hijack_Backdoor_Hangup_B_282_1_Virus_Hijack_Backdoor_Hang_104 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Backdoor.Hangup.B_282_1.vir, Virus.Hijack_Backdoor.Hangup.B_287_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc14ce362462eecf4f5f2121d444475d8c410ec940f79885f519aecfb0a2154c"
    hash2       = "012c488ab987efe901b83cd9790a0cbc9faa756274731d4beb455337d3415130"

  strings:
    $s1  = "2ama0a474smv1gp65rrx9uir2213i79838r70cxu34q23q67n35w35ew3890q350e17k7860ke5e0jjvm0d4jvgg8g68g1ds9v8m65222uu53x1lr3u410f285f40x8r" ascii
    $s2  = " If you extend your subscription, you may continue using the software until" fullword ascii
    $s3  = "parties such as Oracle and instruct your employees and agents of these requirements for the TRMs; (c) restrict disclosure of the" ascii
    $s4  = " contact you. CEIP will also periodically download a small file to your computer.022c1l3853fl14814436l32h08e3n41472eb0b67t48q3kn" ascii
    $s5  = "N. Exportdttlpdxpptxlttphhpxltddltlltxdhhro1nhfs3h92r92mucasqdo0fxh7g3cbr290on67xb130no22469h852cu022798ma34sn8j284ru47c6183depo" ascii
    $s6  = "o772426cll4oxfl676055c9cu71o8r4iofe8t5ehenbt0hqhb2782n7802gmm51pg3mmgj29vvv4m205p0p65256mvj2581331s204information to identify or" ascii
    $s7  = "ss Park, Fairview, Dublin 3, Ireland, Attention: Director of Legal Affairs, Legal Department." fullword ascii
    $s8  = "mkmc5s8ivc2154q65jaw26i3239mf47dm3515rwmu11055l8q5t44j67u20k4xd5e86s0556gse4t22na79ujciuxeul34f9qconvert to a perpetual license." ascii
    $s9  = "of Subscribers. If your business is not defined in the primary definition of Subscriber above, Subscriber is defined as eachi9kq" ascii
    $s10 = "02jvd7o3uc3i33xux4256xr0516205c6l4l47irxifl64qnbbew7q30nt4hq04tq48p9s89sdp5ddjmv46d78m8425v1m7m842jg92Limited, East Point Busine" ascii
    $s11 = "of Subscribers. If your business is not defined in the primary definition of Subscriber above, Subscriber is defined as eachi9kq" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "0a7f863444255ebcacc760d1d0f709b2" and (8 of them)
    ) or (all of them)
}