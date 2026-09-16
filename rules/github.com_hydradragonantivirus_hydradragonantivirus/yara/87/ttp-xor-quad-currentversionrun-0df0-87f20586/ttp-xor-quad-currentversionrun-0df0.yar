rule TTP_XOR_QUAD_CurrentVersionRun_0df0 {
  strings:
    $key_0df0 = { 5e 9f [2] 7a 91 [2] 51 bd [2] 7f 9f [2] 6b 84 [2] 64 9e [2] 7a 83 [2] 78 82 [2] 63 84 [2] 7f 83 [2] 63 ac }

  condition:
    any of them
}