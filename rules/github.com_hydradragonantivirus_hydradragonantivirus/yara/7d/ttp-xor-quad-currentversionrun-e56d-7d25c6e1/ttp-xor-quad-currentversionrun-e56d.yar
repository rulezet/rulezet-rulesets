rule TTP_XOR_QUAD_CurrentVersionRun_e56d {
  strings:
    $key_e56d = { b6 02 [2] 92 0c [2] b9 20 [2] 97 02 [2] 83 19 [2] 8c 03 [2] 92 1e [2] 90 1f [2] 8b 19 [2] 97 1e [2] 8b 31 }

  condition:
    any of them
}