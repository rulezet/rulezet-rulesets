rule TTP_XOR_QUAD_CurrentVersionRun_d9cb {
  strings:
    $key_d9cb = { 8a a4 [2] ae aa [2] 85 86 [2] ab a4 [2] bf bf [2] b0 a5 [2] ae b8 [2] ac b9 [2] b7 bf [2] ab b8 [2] b7 97 }

  condition:
    any of them
}