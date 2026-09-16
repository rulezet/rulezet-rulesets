rule sig_20160525_248e77de2789602108778c6fffe1d4a9 {
  meta:
    description = "datamaliciousorder - file 20160525_248e77de2789602108778c6fffe1d4a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0f71bcfad3922365e6ee94322706f68acd5cedd97656a27ea4b326bac43ede5"

  strings:
    $s1 = "\\n;)(yarrA wen = ma rav    \\n   {\\n)cth(dnenoisilloc noitcnuf\\n\\n\\n;}\\n;)(]dnenoisillocn[gsmb    \\n\\n;)2 ,tsilslianbmuh" ascii
    $s2 = "dart rav\\n;\"56x\\\\l\" = keppelt rav\\n;\"ge6x\\\\\" = ecapsetihwxelft rav\\n;\"86x\\\\t\" = modnart rav'[\"split\"]('')[\"rev" ascii
    $s3 = "nark nruter{)modnark(ecapsetihwxelfk noitcnuf\\n;\"45x\\\\E74x\\\\\" = ssorcak rav\\n;\"56x\\\\l\" = cthk rav\\n;\"tge6x\\\\\" =" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}