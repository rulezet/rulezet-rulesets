rule TTP_XOR_QUAD_CurrentVersionRun_cb16 {
  strings:
    $key_cb16 = { 98 79 [2] bc 77 [2] 97 5b [2] b9 79 [2] ad 62 [2] a2 78 [2] bc 65 [2] be 64 [2] a5 62 [2] b9 65 [2] a5 4a }

  condition:
    any of them
}