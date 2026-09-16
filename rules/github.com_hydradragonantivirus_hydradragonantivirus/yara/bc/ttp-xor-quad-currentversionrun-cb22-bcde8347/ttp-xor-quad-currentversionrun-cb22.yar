rule TTP_XOR_QUAD_CurrentVersionRun_cb22 {
  strings:
    $key_cb22 = { 98 4d [2] bc 43 [2] 97 6f [2] b9 4d [2] ad 56 [2] a2 4c [2] bc 51 [2] be 50 [2] a5 56 [2] b9 51 [2] a5 7e }

  condition:
    any of them
}