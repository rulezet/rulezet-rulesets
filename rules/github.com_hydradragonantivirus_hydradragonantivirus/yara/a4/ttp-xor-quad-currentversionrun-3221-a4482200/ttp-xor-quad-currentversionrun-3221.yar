rule TTP_XOR_QUAD_CurrentVersionRun_3221 {
  strings:
    $key_3221 = { 61 4e [2] 45 40 [2] 6e 6c [2] 40 4e [2] 54 55 [2] 5b 4f [2] 45 52 [2] 47 53 [2] 5c 55 [2] 40 52 [2] 5c 7d }

  condition:
    any of them
}