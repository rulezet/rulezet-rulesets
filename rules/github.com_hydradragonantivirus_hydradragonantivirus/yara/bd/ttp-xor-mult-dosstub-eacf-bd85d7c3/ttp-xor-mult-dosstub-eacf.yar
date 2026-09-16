rule TTP_XOR_MULT_DOSStub_eacf {
  strings:
    $key_eacf = { be a7 [2] ca bf [2] 8d bd [2] ca ac [2] 84 a0 [2] 88 aa [2] 9f a1 [2] 84 ef [2] b9 }

  condition:
    any of them
}