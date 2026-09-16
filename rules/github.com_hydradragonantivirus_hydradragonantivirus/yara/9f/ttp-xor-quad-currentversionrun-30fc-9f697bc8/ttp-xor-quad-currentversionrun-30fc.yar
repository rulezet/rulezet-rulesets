rule TTP_XOR_QUAD_CurrentVersionRun_30fc {
  strings:
    $key_30fc = { 63 93 [2] 47 9d [2] 6c b1 [2] 42 93 [2] 56 88 [2] 59 92 [2] 47 8f [2] 45 8e [2] 5e 88 [2] 42 8f [2] 5e a0 }

  condition:
    any of them
}