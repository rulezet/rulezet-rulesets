rule TTP_XOR_QUAD_CurrentVersionRun_2698 {
  strings:
    $key_2698 = { 75 f7 [2] 51 f9 [2] 7a d5 [2] 54 f7 [2] 40 ec [2] 4f f6 [2] 51 eb [2] 53 ea [2] 48 ec [2] 54 eb [2] 48 c4 }

  condition:
    any of them
}