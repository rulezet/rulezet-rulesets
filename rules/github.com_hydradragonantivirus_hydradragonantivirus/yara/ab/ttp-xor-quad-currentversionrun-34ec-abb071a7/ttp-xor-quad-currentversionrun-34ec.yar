rule TTP_XOR_QUAD_CurrentVersionRun_34ec {
  strings:
    $key_34ec = { 67 83 [2] 43 8d [2] 68 a1 [2] 46 83 [2] 52 98 [2] 5d 82 [2] 43 9f [2] 41 9e [2] 5a 98 [2] 46 9f [2] 5a b0 }

  condition:
    any of them
}