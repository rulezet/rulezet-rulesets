rule TTP_XOR_WriteProcessMemory_86fa {
  strings:
    $key_86fa = { d1 88 [2] e3 aa [2] e5 9f [2] cb 9f [2] f4 83 }

  condition:
    any of them
}