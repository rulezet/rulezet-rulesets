rule TTP_XOR_QUAD_CurrentVersionRun_4b21 {
  strings:
    $key_4b21 = { 18 4e [2] 3c 40 [2] 17 6c [2] 39 4e [2] 2d 55 [2] 22 4f [2] 3c 52 [2] 3e 53 [2] 25 55 [2] 39 52 [2] 25 7d }

  condition:
    any of them
}