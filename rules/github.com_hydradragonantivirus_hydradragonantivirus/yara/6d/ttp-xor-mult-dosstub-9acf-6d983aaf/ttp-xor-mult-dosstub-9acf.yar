rule TTP_XOR_MULT_DOSStub_9acf {
  strings:
    $key_9acf = { ce a7 [2] ba bf [2] fd bd [2] ba ac [2] f4 a0 [2] f8 aa [2] ef a1 [2] f4 ef [2] c9 }

  condition:
    any of them
}