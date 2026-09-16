rule TTP_XOR_WriteProcessMemory_8ecf {
  strings:
    $key_8ecf = { d9 bd [2] eb 9f [2] ed aa [2] c3 aa [2] fc b6 }

  condition:
    any of them
}