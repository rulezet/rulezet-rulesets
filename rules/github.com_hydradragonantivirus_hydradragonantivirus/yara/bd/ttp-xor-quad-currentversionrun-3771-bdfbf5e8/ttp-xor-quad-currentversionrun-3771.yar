rule TTP_XOR_QUAD_CurrentVersionRun_3771 {
  strings:
    $key_3771 = { 64 1e [2] 40 10 [2] 6b 3c [2] 45 1e [2] 51 05 [2] 5e 1f [2] 40 02 [2] 42 03 [2] 59 05 [2] 45 02 [2] 59 2d }

  condition:
    any of them
}