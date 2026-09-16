rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160921_4855f7b1e1da_4704 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_731724a743a10eb03d2ee3a92239f369.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash3       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"

  strings:
    $s1 = "tion f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s2 = "){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})" ascii
    $s3 = "tion f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s4 = "n f000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii
    $s5 = "turn \"Do\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}