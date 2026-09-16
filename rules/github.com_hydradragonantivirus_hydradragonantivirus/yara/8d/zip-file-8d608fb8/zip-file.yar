rule zip_file
{
  strings:
    $magic = { 50 4b 03 04 }
    $magic2 = { 50 4b 05 06 }
    $magic3 = { 50 4b 07 08 }
  condition:
    ($magic at 0) or ($magic2 at 0) or ($magic3 at 0)
}