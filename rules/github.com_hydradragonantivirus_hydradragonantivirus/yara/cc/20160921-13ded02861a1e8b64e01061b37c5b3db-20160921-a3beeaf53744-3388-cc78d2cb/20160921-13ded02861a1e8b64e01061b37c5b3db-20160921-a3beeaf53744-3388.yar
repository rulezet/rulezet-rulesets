rule _20160921_13ded02861a1e8b64e01061b37c5b3db_20160921_a3beeaf53744_3388 {
  meta:
    description = "datamaliciousorder - from files 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash2       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash3       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"
    hash4       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"

  strings:
    $s1 = "c\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function" ascii
    $s2 = ";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii
    $s3 = "on f000(){return \"Wh\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s4 = "turn \"WIj\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})()" ascii
    $s5 = "\"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Go\";})(),(funct" ascii
    $s6 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Nx\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}