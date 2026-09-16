rule TTP_XOR_QUAD_CurrentVersionRun_d935 {
  strings:
    $key_d935 = { 8a 5a [2] ae 54 [2] 85 78 [2] ab 5a [2] bf 41 [2] b0 5b [2] ae 46 [2] ac 47 [2] b7 41 [2] ab 46 [2] b7 69 }

  condition:
    any of them
}