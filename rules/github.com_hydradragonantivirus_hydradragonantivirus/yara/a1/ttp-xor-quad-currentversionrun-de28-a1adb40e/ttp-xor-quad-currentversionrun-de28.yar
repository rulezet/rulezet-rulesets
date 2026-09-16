rule TTP_XOR_QUAD_CurrentVersionRun_de28 {
  strings:
    $key_de28 = { 8d 47 [2] a9 49 [2] 82 65 [2] ac 47 [2] b8 5c [2] b7 46 [2] a9 5b [2] ab 5a [2] b0 5c [2] ac 5b [2] b0 74 }

  condition:
    any of them
}