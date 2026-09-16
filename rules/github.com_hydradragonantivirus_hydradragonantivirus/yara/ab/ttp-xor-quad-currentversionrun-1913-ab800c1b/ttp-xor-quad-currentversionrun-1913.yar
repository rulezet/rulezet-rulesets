rule TTP_XOR_QUAD_CurrentVersionRun_1913 {
  strings:
    $key_1913 = { 4a 7c [2] 6e 72 [2] 45 5e [2] 6b 7c [2] 7f 67 [2] 70 7d [2] 6e 60 [2] 6c 61 [2] 77 67 [2] 6b 60 [2] 77 4f }

  condition:
    any of them
}