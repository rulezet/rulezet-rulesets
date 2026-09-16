rule TTP_XOR_QUAD_CurrentVersionRun_e513 {
  strings:
    $key_e513 = { b6 7c [2] 92 72 [2] b9 5e [2] 97 7c [2] 83 67 [2] 8c 7d [2] 92 60 [2] 90 61 [2] 8b 67 [2] 97 60 [2] 8b 4f }

  condition:
    any of them
}