rule TTP_XOR_QUAD_CurrentVersionRun_29e2 {
  strings:
    $key_29e2 = { 7a 8d [2] 5e 83 [2] 75 af [2] 5b 8d [2] 4f 96 [2] 40 8c [2] 5e 91 [2] 5c 90 [2] 47 96 [2] 5b 91 [2] 47 be }

  condition:
    any of them
}