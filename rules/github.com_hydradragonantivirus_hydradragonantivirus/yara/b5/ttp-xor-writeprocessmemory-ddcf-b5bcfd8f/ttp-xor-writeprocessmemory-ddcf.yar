rule TTP_XOR_WriteProcessMemory_ddcf {
  strings:
    $key_ddcf = { 8a bd [2] b8 9f [2] be aa [2] 90 aa [2] af b6 }

  condition:
    any of them
}