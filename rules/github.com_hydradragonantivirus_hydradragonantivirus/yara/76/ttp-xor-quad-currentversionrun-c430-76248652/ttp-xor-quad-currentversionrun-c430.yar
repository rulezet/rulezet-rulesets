rule TTP_XOR_QUAD_CurrentVersionRun_c430 {
  strings:
    $key_c430 = { 97 5f [2] b3 51 [2] 98 7d [2] b6 5f [2] a2 44 [2] ad 5e [2] b3 43 [2] b1 42 [2] aa 44 [2] b6 43 [2] aa 6c }

  condition:
    any of them
}