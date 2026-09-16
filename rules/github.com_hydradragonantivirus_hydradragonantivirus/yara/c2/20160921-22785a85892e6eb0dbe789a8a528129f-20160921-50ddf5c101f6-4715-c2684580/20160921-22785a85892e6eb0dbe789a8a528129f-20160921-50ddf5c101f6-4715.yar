rule _20160921_22785a85892e6eb0dbe789a8a528129f_20160921_50ddf5c101f6_4715 {
  meta:
    description = "datamaliciousorder - from files 20160921_22785a85892e6eb0dbe789a8a528129f.js, 20160921_50ddf5c101f65dbae1a99b5967b69eaf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bd9f1cc39c45e7b6963f5eca04b26ef2eaf9c8005e5a0d5f12e868261ae58ca"
    hash2       = "4d3df92f56e6b5cba10c96e8cd182f92f3c10aceaabe5a4530b70d3fc5873feb"

  strings:
    $s1 = "(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\"" ascii
    $s2 = "{return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(" ascii
    $s3 = "f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RP" ascii
    $s4 = ",(function f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s5 = "rn \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}