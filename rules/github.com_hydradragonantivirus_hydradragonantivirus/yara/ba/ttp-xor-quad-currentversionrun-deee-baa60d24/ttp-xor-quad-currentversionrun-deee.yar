rule TTP_XOR_QUAD_CurrentVersionRun_deee {
  strings:
    $key_deee = { 8d 81 [2] a9 8f [2] 82 a3 [2] ac 81 [2] b8 9a [2] b7 80 [2] a9 9d [2] ab 9c [2] b0 9a [2] ac 9d [2] b0 b2 }

  condition:
    any of them
}