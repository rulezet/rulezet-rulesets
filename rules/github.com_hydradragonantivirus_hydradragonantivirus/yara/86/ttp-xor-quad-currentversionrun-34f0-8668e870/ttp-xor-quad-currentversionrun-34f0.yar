rule TTP_XOR_QUAD_CurrentVersionRun_34f0 {
  strings:
    $key_34f0 = { 67 9f [2] 43 91 [2] 68 bd [2] 46 9f [2] 52 84 [2] 5d 9e [2] 43 83 [2] 41 82 [2] 5a 84 [2] 46 83 [2] 5a ac }

  condition:
    any of them
}