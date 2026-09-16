rule TTP_XOR_QUAD_CurrentVersionRun_1621 {
  strings:
    $key_1621 = { 45 4e [2] 61 40 [2] 4a 6c [2] 64 4e [2] 70 55 [2] 7f 4f [2] 61 52 [2] 63 53 [2] 78 55 [2] 64 52 [2] 78 7d }

  condition:
    any of them
}