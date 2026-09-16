rule TTP_XOR_QUAD_CurrentVersionRun_3fed {
  strings:
    $key_3fed = { 6c 82 [2] 48 8c [2] 63 a0 [2] 4d 82 [2] 59 99 [2] 56 83 [2] 48 9e [2] 4a 9f [2] 51 99 [2] 4d 9e [2] 51 b1 }

  condition:
    any of them
}