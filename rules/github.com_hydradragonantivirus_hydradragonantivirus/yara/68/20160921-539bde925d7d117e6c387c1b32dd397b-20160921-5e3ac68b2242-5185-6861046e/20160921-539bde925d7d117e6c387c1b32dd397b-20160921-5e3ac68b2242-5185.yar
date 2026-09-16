rule _20160921_539bde925d7d117e6c387c1b32dd397b_20160921_5e3ac68b2242_5185 {
  meta:
    description = "datamaliciousorder - from files 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_5e3ac68b2242250176f3300039d176f6.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash2       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"
    hash3       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1 = "f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Z" ascii
    $s2 = "n \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s3 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz\";})(),(f" ascii
    $s4 = "tion f000(){return \"NYh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s5 = "),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}