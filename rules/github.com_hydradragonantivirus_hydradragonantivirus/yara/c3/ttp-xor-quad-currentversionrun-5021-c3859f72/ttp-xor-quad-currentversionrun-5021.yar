rule TTP_XOR_QUAD_CurrentVersionRun_5021 {
  strings:
    $key_5021 = { 03 4e [2] 27 40 [2] 0c 6c [2] 22 4e [2] 36 55 [2] 39 4f [2] 27 52 [2] 25 53 [2] 3e 55 [2] 22 52 [2] 3e 7d }

  condition:
    any of them
}