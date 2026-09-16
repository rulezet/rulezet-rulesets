rule _20160921_26653257e0da59c861fc658d3bccdafd_20160921_2bac0af1f20f_4754 {
  meta:
    description = "datamaliciousorder - from files 20160921_26653257e0da59c861fc658d3bccdafd.js, 20160921_2bac0af1f20f4cf23b85236dea7e2f73.js, 20160921_336aeb1d023bcb845a70471edfe8a8f9.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_8f9ae4533bfbaedf1feae61032904250.js, 20160921_cd62091b54940830ea3695d380fd97d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dff3cae9c135714cad3879ac1ef904841ec9264e3448106fbedd3b57ca11e97"
    hash2       = "ac846ac68af7b06cbf71b32cbfb1cee6c1f6cd131d52124bb877e0b27979fd81"
    hash3       = "f77fe3497bb26b47e909d597cb0055c997e8149b22c878594ee85d0303c27381"
    hash4       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash5       = "f093836b93b9b87ed10341ee30bc818ac497c91c6d0dd2b00ab5d3b1822868f9"
    hash6       = "e00553588533d1015b71812c5877864382cbfd2a3a204b4cab76c38ee65ce58c"

  strings:
    $s1 = " fuck(){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MB" ascii
    $s2 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){" ascii
    $s3 = "k(){return \"Fv\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";}" ascii
    $s4 = ";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuc" ascii
    $s5 = "turn \"Ik\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MUs\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}