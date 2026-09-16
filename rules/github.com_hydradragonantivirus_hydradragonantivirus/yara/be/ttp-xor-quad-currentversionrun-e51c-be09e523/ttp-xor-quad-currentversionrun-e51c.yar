rule TTP_XOR_QUAD_CurrentVersionRun_e51c {
  strings:
    $key_e51c = { b6 73 [2] 92 7d [2] b9 51 [2] 97 73 [2] 83 68 [2] 8c 72 [2] 92 6f [2] 90 6e [2] 8b 68 [2] 97 6f [2] 8b 40 }

  condition:
    any of them
}