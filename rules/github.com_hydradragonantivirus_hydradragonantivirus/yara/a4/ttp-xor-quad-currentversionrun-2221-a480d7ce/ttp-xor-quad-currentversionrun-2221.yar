rule TTP_XOR_QUAD_CurrentVersionRun_2221 {
  strings:
    $key_2221 = { 71 4e [2] 55 40 [2] 7e 6c [2] 50 4e [2] 44 55 [2] 4b 4f [2] 55 52 [2] 57 53 [2] 4c 55 [2] 50 52 [2] 4c 7d }

  condition:
    any of them
}