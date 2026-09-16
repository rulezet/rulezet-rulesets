rule TTP_XOR_QUAD_CurrentVersionRun_3621 {
  strings:
    $key_3621 = { 65 4e [2] 41 40 [2] 6a 6c [2] 44 4e [2] 50 55 [2] 5f 4f [2] 41 52 [2] 43 53 [2] 58 55 [2] 44 52 [2] 58 7d }

  condition:
    any of them
}