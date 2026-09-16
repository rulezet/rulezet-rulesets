rule TTP_XOR_QUAD_CurrentVersionRun_ff53 {
  strings:
    $key_ff53 = { ac 3c [2] 88 32 [2] a3 1e [2] 8d 3c [2] 99 27 [2] 96 3d [2] 88 20 [2] 8a 21 [2] 91 27 [2] 8d 20 [2] 91 0f }

  condition:
    any of them
}