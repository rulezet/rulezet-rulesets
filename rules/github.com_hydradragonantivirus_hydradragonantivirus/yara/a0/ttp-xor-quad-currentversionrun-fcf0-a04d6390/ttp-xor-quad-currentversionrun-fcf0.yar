rule TTP_XOR_QUAD_CurrentVersionRun_fcf0 {
  strings:
    $key_fcf0 = { af 9f [2] 8b 91 [2] a0 bd [2] 8e 9f [2] 9a 84 [2] 95 9e [2] 8b 83 [2] 89 82 [2] 92 84 [2] 8e 83 [2] 92 ac }

  condition:
    any of them
}