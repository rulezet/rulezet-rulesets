rule TTP_XOR_QUAD_CurrentVersionRun_00fc {
  strings:
    $key_00fc = { 53 93 [2] 77 9d [2] 5c b1 [2] 72 93 [2] 66 88 [2] 69 92 [2] 77 8f [2] 75 8e [2] 6e 88 [2] 72 8f [2] 6e a0 }

  condition:
    any of them
}