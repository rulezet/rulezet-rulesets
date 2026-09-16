rule TTP_XOR_QUAD_CurrentVersionRun_7621 {
  strings:
    $key_7621 = { 25 4e [2] 01 40 [2] 2a 6c [2] 04 4e [2] 10 55 [2] 1f 4f [2] 01 52 [2] 03 53 [2] 18 55 [2] 04 52 [2] 18 7d }

  condition:
    any of them
}