rule TTP_XOR_QUAD_CurrentVersionRun_24f0 {
  strings:
    $key_24f0 = { 77 9f [2] 53 91 [2] 78 bd [2] 56 9f [2] 42 84 [2] 4d 9e [2] 53 83 [2] 51 82 [2] 4a 84 [2] 56 83 [2] 4a ac }

  condition:
    any of them
}