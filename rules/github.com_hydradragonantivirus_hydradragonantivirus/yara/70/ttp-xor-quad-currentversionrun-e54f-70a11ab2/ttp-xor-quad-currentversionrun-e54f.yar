rule TTP_XOR_QUAD_CurrentVersionRun_e54f {
  strings:
    $key_e54f = { b6 20 [2] 92 2e [2] b9 02 [2] 97 20 [2] 83 3b [2] 8c 21 [2] 92 3c [2] 90 3d [2] 8b 3b [2] 97 3c [2] 8b 13 }

  condition:
    any of them
}