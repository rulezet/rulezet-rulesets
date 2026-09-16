rule TTP_XOR_QUAD_CurrentVersionRun_fb63 {
  strings:
    $key_fb63 = { a8 0c [2] 8c 02 [2] a7 2e [2] 89 0c [2] 9d 17 [2] 92 0d [2] 8c 10 [2] 8e 11 [2] 95 17 [2] 89 10 [2] 95 3f }

  condition:
    any of them
}