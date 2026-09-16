rule gif_file
{
  strings:
    $gif89a = { 47 49 46 38 39 61 }
    $gif87a = { 47 49 46 38 37 61 }
  condition:
    ( $gif89a at 0 ) or ( $gif87a at 0 )
}