rule TTP_XOR_QUAD_CurrentVersionRun_de32 {
  strings:
    $key_de32 = { 8d 5d [2] a9 53 [2] 82 7f [2] ac 5d [2] b8 46 [2] b7 5c [2] a9 41 [2] ab 40 [2] b0 46 [2] ac 41 [2] b0 6e }

  condition:
    any of them
}