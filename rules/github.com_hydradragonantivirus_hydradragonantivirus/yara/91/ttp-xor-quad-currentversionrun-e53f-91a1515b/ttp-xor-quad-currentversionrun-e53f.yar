rule TTP_XOR_QUAD_CurrentVersionRun_e53f {
  strings:
    $key_e53f = { b6 50 [2] 92 5e [2] b9 72 [2] 97 50 [2] 83 4b [2] 8c 51 [2] 92 4c [2] 90 4d [2] 8b 4b [2] 97 4c [2] 8b 63 }

  condition:
    any of them
}