rule TTP_XOR_QUAD_CurrentVersionRun_2921 {
  strings:
    $key_2921 = { 7a 4e [2] 5e 40 [2] 75 6c [2] 5b 4e [2] 4f 55 [2] 40 4f [2] 5e 52 [2] 5c 53 [2] 47 55 [2] 5b 52 [2] 47 7d }

  condition:
    any of them
}