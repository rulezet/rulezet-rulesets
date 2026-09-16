rule TTP_XOR_QUAD_CurrentVersionRun_e52d {
  strings:
    $key_e52d = { b6 42 [2] 92 4c [2] b9 60 [2] 97 42 [2] 83 59 [2] 8c 43 [2] 92 5e [2] 90 5f [2] 8b 59 [2] 97 5e [2] 8b 71 }

  condition:
    any of them
}