rule TTP_XOR_QUAD_CurrentVersionRun_e46d {
  strings:
    $key_e46d = { b7 02 [2] 93 0c [2] b8 20 [2] 96 02 [2] 82 19 [2] 8d 03 [2] 93 1e [2] 91 1f [2] 8a 19 [2] 96 1e [2] 8a 31 }

  condition:
    any of them
}