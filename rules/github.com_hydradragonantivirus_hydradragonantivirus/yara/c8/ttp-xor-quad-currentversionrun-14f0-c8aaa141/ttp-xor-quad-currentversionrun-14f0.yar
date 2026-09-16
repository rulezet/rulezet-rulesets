rule TTP_XOR_QUAD_CurrentVersionRun_14f0 {
  strings:
    $key_14f0 = { 47 9f [2] 63 91 [2] 48 bd [2] 66 9f [2] 72 84 [2] 7d 9e [2] 63 83 [2] 61 82 [2] 7a 84 [2] 66 83 [2] 7a ac }

  condition:
    any of them
}